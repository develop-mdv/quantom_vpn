package vpn.myboroda.omega

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView

/// Shared dark palette for all screens. The app deliberately sticks to
/// platform widgets (no androidx/material) to stay tiny, so the look is
/// defined entirely by these colors plus the drawables below.
object Palette {
    val BG = Color.rgb(17, 20, 24)
    val PANEL = Color.rgb(26, 32, 39)
    val PANEL_SOFT = Color.rgb(33, 41, 51)
    val BORDER = Color.rgb(43, 52, 64)
    val TEXT = Color.rgb(238, 244, 247)
    val MUTED = Color.rgb(152, 167, 179)
    val ACCENT = Color.rgb(54, 211, 153)
    val AMBER = Color.rgb(251, 189, 35)
    val DANGER = Color.rgb(248, 114, 114)
}

internal fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

/// Standard screen root: dark scrollable column. fitsSystemWindows pads the
/// content away from the status/navigation bars — targetSdk 35 forces
/// edge-to-edge, so without it the header lands under the status bar and
/// its buttons are hard to reach.
internal fun Context.uiScreenRoot(): ScrollView {
    return ScrollView(this).apply {
        setBackgroundColor(Palette.BG)
        isFillViewport = true
        fitsSystemWindows = true
    }
}

internal fun Context.roundedRect(fill: Int, radiusDp: Int, stroke: Int): GradientDrawable {
    return GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(radiusDp).toFloat()
        setStroke(dp(1), stroke)
    }
}

internal fun Context.circle(fill: Int, stroke: Int, strokeDp: Int = 1): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(fill)
        setStroke(dp(strokeDp), stroke)
    }
}

/// Card with an optional bold title; adds its own bottom spacing so screens
/// can just stack panels in a vertical LinearLayout.
internal fun Context.uiPanel(title: String?, vararg children: View): View {
    val box = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(14), dp(16), dp(16))
        background = roundedRect(Palette.PANEL, 12, Palette.BORDER)
    }
    if (title != null) {
        box.addView(TextView(this).apply {
            text = title
            textSize = 17f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Palette.TEXT)
        })
        box.addView(uiSpace(1, dp(10)))
    }
    children.forEach { box.addView(it) }
    return LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, 0, 0, dp(14))
        addView(box)
    }
}

internal fun Context.uiInput(hintText: String): EditText {
    return EditText(this).apply {
        hint = hintText
        textSize = 15f
        setSingleLine(false)
        minLines = 1
        maxLines = 3
        setTextColor(Palette.TEXT)
        setHintTextColor(Palette.MUTED)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        background = roundedRect(Color.TRANSPARENT, 8, Palette.BORDER)
    }
}

internal fun Context.uiButton(textValue: String, onClick: () -> Unit): Button {
    return Button(this).apply {
        text = textValue
        textSize = 14f
        isAllCaps = false
        setTextColor(Palette.BG)
        typeface = Typeface.DEFAULT_BOLD
        background = roundedRect(Palette.ACCENT, 8, Palette.ACCENT)
        setOnClickListener { onClick() }
    }
}

/// Bordered text button without a fill — secondary actions.
internal fun Context.uiGhostButton(textValue: String, color: Int = Palette.TEXT, onClick: () -> Unit): TextView {
    return TextView(this).apply {
        text = textValue
        textSize = 14f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(color)
        gravity = Gravity.CENTER
        setPadding(dp(12), dp(8), dp(12), dp(8))
        background = roundedRect(Color.TRANSPARENT, 8, color)
        setOnClickListener { onClick() }
    }
}

/// Square tappable glyph (⚙, ✎, ✕, ←) — the app has no icon assets beyond
/// the logo, so toolbar/row actions are unicode glyphs on a panel chip.
internal fun Context.uiIconButton(
    glyph: String,
    tint: Int = Palette.MUTED,
    sizeDp: Int = 44,
    onClick: () -> Unit,
): TextView {
    return TextView(this).apply {
        text = glyph
        textSize = 18f
        gravity = Gravity.CENTER
        setTextColor(tint)
        background = roundedRect(Palette.PANEL, 10, Palette.BORDER)
        layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
        setOnClickListener { onClick() }
    }
}

internal fun Context.uiLabel(textValue: String): TextView {
    return TextView(this).apply {
        text = textValue
        textSize = 13f
        setTextColor(Palette.MUTED)
        setPadding(0, dp(8), 0, dp(5))
    }
}

internal fun Context.uiSpinner(items: List<String>): Spinner {
    return Spinner(this).apply {
        adapter = ArrayAdapter(this@uiSpinner, android.R.layout.simple_spinner_dropdown_item, items)
        background = roundedRect(Color.TRANSPARENT, 8, Palette.BORDER)
        setPadding(dp(8), dp(6), dp(8), dp(6))
    }
}

internal fun Context.uiSpace(width: Int, height: Int): View {
    return View(this).apply {
        layoutParams = LinearLayout.LayoutParams(width, height)
    }
}

/// Back arrow + bold title row for secondary screens.
internal fun Activity.screenHeader(title: String): View {
    val row = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, 0, 0, dp(16))
    }
    row.addView(uiIconButton("←", tint = Palette.TEXT) { finish() })
    row.addView(
        TextView(this).apply {
            text = title
            textSize = 22f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Palette.TEXT)
            setPadding(dp(12), 0, 0, 0)
        },
        weightParams(),
    )
    return row
}

internal fun weightParams(): LinearLayout.LayoutParams {
    return LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
}

internal fun simpleTextWatcher(onChange: () -> Unit): TextWatcher {
    return object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = onChange()
        override fun afterTextChanged(s: Editable?) = Unit
    }
}

internal class SimpleItemSelectedListener(private val onSelected: () -> Unit) :
    AdapterView.OnItemSelectedListener {
    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) = onSelected()
    override fun onNothingSelected(parent: AdapterView<*>?) = Unit
}
