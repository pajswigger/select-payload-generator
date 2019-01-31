package burp

import javax.swing.JMenuItem


class BurpExtender: IBurpExtender {
    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
    }
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Companion.callbacks = callbacks
        callbacks.setExtensionName("Select Payload Generator")
        callbacks.registerContextMenuFactory(ContextMenuFactory())
    }
}


class ContextMenuFactory: IContextMenuFactory {
    val applicableContexts = listOf(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE)

    override fun createMenuItems(invocation: IContextMenuInvocation): List<JMenuItem> {
        val response = invocation.selectedMessages!![0].response
        if (invocation.invocationContext in applicableContexts && response != null
                && findEnclosingSelect(getHtml(response), invocation.selectionBounds[0]) != null) {
            val menuItem = JMenuItem("Create payload from options")
            menuItem.addActionListener {
                val options = getOptions(response, invocation.selectionBounds[0])
                BurpExtender.callbacks.registerIntruderPayloadGeneratorFactory(IntruderPayloadGeneratorFactory("Select Payload", options))
            }
            return listOf(menuItem)
        }
        return emptyList()
    }
}


fun getHtml(response: ByteArray): String {
    val helpers = BurpExtender.callbacks.helpers
    val responseInfo = helpers.analyzeResponse(response)
    return String(response.copyOfRange(responseInfo.bodyOffset, response.size))
}


fun findEnclosingSelect(html: String, selectionOffset: Int): Int? {
    val selectRegex = Regex("<select", RegexOption.IGNORE_CASE)
    val selectsBefore = selectRegex.findAll(html).filter{ it.range.start < selectionOffset }.toList()
    return selectsBefore.lastOrNull()?.range?.start
}


fun getOptions(response: ByteArray, selectionOffset: Int): List<ByteArray> {
    val html = getHtml(response)
    val startIndex = findEnclosingSelect(html, selectionOffset)!!
    val endSelectRegex = Regex("</select", RegexOption.IGNORE_CASE)

    val endIndex = endSelectRegex.find(html, startIndex)?.range?.endInclusive ?: html.length

    val optionRegex = Regex("<option.*value=\"(.*)\"", RegexOption.IGNORE_CASE)
    return optionRegex.findAll(html, startIndex)
                                    .filter { it.range.endInclusive < endIndex }
                                    .map { it.groupValues[1].toByteArray() }
                                    .toList()
}


class IntruderPayloadGeneratorFactory(override val generatorName: String, val payloads: List<ByteArray>) : IIntruderPayloadGeneratorFactory {
    override fun createNewInstance(attack: IIntruderAttack) = IntruderPayloadGenerator(payloads)
}


class IntruderPayloadGenerator(val payloads: List<ByteArray>): IIntruderPayloadGenerator {
    var index = 0
    override fun getNextPayload(baseValue: ByteArray?) = payloads[index++]
    override fun hasMorePayloads() = index < payloads.size
    override fun reset() {
        index = 0
    }
}
